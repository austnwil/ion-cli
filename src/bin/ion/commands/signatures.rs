use crate::commands::{CommandIo, IonCliCommand, WithIonCliArgument};
use anyhow::Result;
use clap::{ArgMatches, Command};
use ion_rs::*;
use std::collections::HashMap;

pub struct SignaturesCommand;

impl IonCliCommand for SignaturesCommand {
    fn name(&self) -> &'static str {
        "signatures"
    }

    fn about(&self) -> &'static str {
        "Detect repeated signatures for Ion container types"
    }

    fn is_stable(&self) -> bool {
        false
    }

    fn configure_args(&self, command: Command) -> Command {
        command
            .long_about("Analyzes Ion input to detect repeated signatures for container types (struct, list, sexp).\n\
                Two objects have the same signature if:\n\
                - Both structs have the same fields with the same types\n\
                - Both lists/sexps have the same number of elements with the same types in order")
            .with_input()
            .with_output()
            .arg(clap::Arg::new("min-signature-size")
                .long("min-signature-size")
                .value_parser(clap::value_parser!(usize))
                .default_value("2")
                .help("Minimum size for signatures to be registered (default: 2)"))
    }

    fn run(&self, _command_path: &mut Vec<String>, args: &ArgMatches) -> Result<()> {
        let min_size = *args.get_one::<usize>("min-signature-size").unwrap();
        let mut signature_registry = SignatureRegistry::new();
        
        CommandIo::new(args)?.for_each_input(|_output, input| {
            let mut reader = SystemReader::new(AnyEncoding, input.into_source());
            
            loop {
                match reader.next_item()? {
                    SystemStreamItem::EndOfStream(_) => break,
                    SystemStreamItem::Value(value) => {
                        collect_signatures(value, &mut signature_registry, min_size, true)?;
                    }
                    _ => continue,
                }
            }
            Ok(())
        })?;

        // Inline signatures with only one parent
        signature_registry.inline_single_parent_signatures();
        
        // Output results
        let mut sorted_entries: Vec<_> = signature_registry.id_to_signature.iter().collect();
        sorted_entries.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        for (id, entry) in sorted_entries {
            println!("{} values appear with signature #{} {}", entry.count, id, entry.signature.display(&signature_registry));
        }

        Ok(())
    }
}

type SignatureId = usize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TypeSignature {
    Null,
    Bool,
    Int,
    Float,
    Decimal,
    Timestamp,
    String,
    Symbol,
    Blob,
    Clob,
    Container(SignatureId),
    Verbatim(ContainerSignature),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ContainerSignature {
    Struct(Vec<(String, TypeSignature)>),
    List(Vec<TypeSignature>),
    SExp(Vec<TypeSignature>),
}

#[derive(Debug)]
struct SignatureRegistryEntry {
    signature: ContainerSignature,
    count: usize,
    parent_count: usize,
    appears_top_level: bool
}

struct SignatureRegistry {
    id_to_signature: HashMap<SignatureId, SignatureRegistryEntry>,
    signature_to_id: HashMap<ContainerSignature, SignatureId>,
    next_id: SignatureId,
}

impl SignatureRegistry {
    fn new() -> Self {
        Self {
            id_to_signature: HashMap::new(),
            signature_to_id: HashMap::new(),
            next_id: 0
        }
    }
    
    // Returns (true, id) if entry is already present, (false, id) if it was not
    fn get_or_create_id(&mut self, signature: ContainerSignature, top_level: bool) -> (bool, SignatureId) {
        if let Some(&id) = self.signature_to_id.get(&signature) {
            let entry = self.id_to_signature.get_mut(&id).unwrap();
            entry.count += 1;
            entry.appears_top_level |= top_level;
            (true, id)
        } else {
            let id = self.next_id;
            self.next_id += 1;
            self.id_to_signature.insert(id, SignatureRegistryEntry {
                signature: signature.clone(),
                count: 1,
                parent_count: 0,
                appears_top_level: top_level
            });
            self.signature_to_id.insert(signature, id);
            (false, id)
        }
    }
    
    fn inline_single_parent_signatures(&mut self) {
        let single_parent_ids: Vec<SignatureId> = self.id_to_signature.iter()
            .filter(|(_, entry)| entry.parent_count == 1 && ! entry.appears_top_level)
            .map(|(&id, _)| id)
            .collect();
        
        for id in single_parent_ids {
            let signature_to_inline = self.id_to_signature[&id].signature.clone();
            
            for entry in self.id_to_signature.values_mut() {
                Self::replace_container_refs(&mut entry.signature, id, &signature_to_inline);
            }
            
            self.id_to_signature.remove(&id);
        }
    }
    
    fn replace_container_refs(sig: &mut ContainerSignature, target_id: SignatureId, replacement: &ContainerSignature) {
        match sig {
            ContainerSignature::Struct(fields) => {
                for (_, typ) in fields {
                    if let TypeSignature::Container(id) = typ {
                        if *id == target_id {
                            *typ = TypeSignature::Verbatim(replacement.clone());
                        }
                    }
                }
            }
            ContainerSignature::List(elements) | ContainerSignature::SExp(elements) => {
                for typ in elements {
                    if let TypeSignature::Container(id) = typ {
                        if *id == target_id {
                            *typ = TypeSignature::Verbatim(replacement.clone());
                        }
                    }
                }
            }
        }
    }
}

impl ContainerSignature {
    fn size(&self, registry: &SignatureRegistry) -> usize {
        match self {
            ContainerSignature::Struct(fields) => {
                fields.len() + fields.iter().map(|(_, typ)| typ.container_size(registry)).sum::<usize>()
            }
            ContainerSignature::List(elements) => {
                elements.len() + elements.iter().map(|typ| typ.container_size(registry)).sum::<usize>()
            }
            ContainerSignature::SExp(elements) => {
                elements.len() + elements.iter().map(|typ| typ.container_size(registry)).sum::<usize>()
            }
        }
    }
    
    fn display(&self, registry: &SignatureRegistry) -> String {
        match self {
            ContainerSignature::Struct(fields) => {
                let field_strs: Vec<String> = fields.iter().map(|(name, typ)| {
                    format!("{}: {}", name, typ.display(registry))
                }).collect();
                format!("{{ {} }}", field_strs.join(", "))
            }
            ContainerSignature::List(elements) => {
                let elem_strs: Vec<String> = elements.iter().map(|typ| typ.display(registry)).collect();
                format!("[ {} ]", elem_strs.join(", "))
            }
            ContainerSignature::SExp(elements) => {
                let elem_strs: Vec<String> = elements.iter().map(|typ| typ.display(registry)).collect();
                format!("( {} )", elem_strs.join(" "))
            }
        }
    }
}

impl TypeSignature {
    fn container_size(&self, registry: &SignatureRegistry) -> usize {
        match self {
            TypeSignature::Container(id) => registry.id_to_signature[id].signature.size(registry),
            TypeSignature::Verbatim(sig) => sig.size(registry),
            _ => 0,
        }
    }
    
    fn display(&self, registry: &SignatureRegistry) -> String {
        match self {
            TypeSignature::Null => "null".to_string(),
            TypeSignature::Bool => "bool".to_string(),
            TypeSignature::Int => "int".to_string(),
            TypeSignature::Float => "float".to_string(),
            TypeSignature::Decimal => "decimal".to_string(),
            TypeSignature::Timestamp => "timestamp".to_string(),
            TypeSignature::String => "string".to_string(),
            TypeSignature::Symbol => "symbol".to_string(),
            TypeSignature::Blob => "blob".to_string(),
            TypeSignature::Clob => "clob".to_string(),
            TypeSignature::Container(id) => format!("(#{})", *id),
            TypeSignature::Verbatim(sig) => sig.display(registry),
        }
    }
}

fn collect_sequence_signatures<'a, I>(
    elements_iter: I,
    registry: &mut SignatureRegistry,
    min_size: usize,
    top_level: bool,
    signature_constructor: impl FnOnce(Vec<TypeSignature>) -> ContainerSignature,
) -> Result<TypeSignature>
where
    I: Iterator<Item = Result<LazyValue<'a, AnyEncoding>, IonError>>,
{
    let mut elements = Vec::new();
    for element in elements_iter {
        let element_type = collect_signatures(element?, registry, min_size, false)?;
        elements.push(element_type);
    }
    let container_sig = signature_constructor(elements.clone());
    if container_sig.size(registry) >= min_size {
        let (existing, id) = registry.get_or_create_id(container_sig, top_level);
        if !existing {
            for typ in &elements {
                if let TypeSignature::Container(child_id) = typ {
                    registry.id_to_signature.get_mut(child_id).unwrap().parent_count += 1;
                }
            }
        }
        Ok(TypeSignature::Container(id))
    } else {
        Ok(TypeSignature::Verbatim(container_sig))
    }
}

fn collect_signatures(value: LazyValue<AnyEncoding>, registry: &mut SignatureRegistry, min_size: usize, top_level: bool) -> Result<TypeSignature> {
    use ValueRef::*;
    Ok(match value.read()? {
        Null(_) => TypeSignature::Null,
        Bool(_) => TypeSignature::Bool,
        Int(_) => TypeSignature::Int,
        Float(_) => TypeSignature::Float,
        Decimal(_) => TypeSignature::Decimal,
        Timestamp(_) => TypeSignature::Timestamp,
        String(_) => TypeSignature::String,
        Symbol(_) => TypeSignature::Symbol,
        Blob(_) => TypeSignature::Blob,
        Clob(_) => TypeSignature::Clob,
        Struct(s) => {
            let mut fields = Vec::new();
            for field in s {
                let field = field?;
                let field_name = field.name()?.text().unwrap_or("").to_string();
                let field_type = collect_signatures(field.value(), registry, min_size, false)?;
                fields.push((field_name, field_type));
            }
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            let container_sig = ContainerSignature::Struct(fields.clone());
            if container_sig.size(registry) >= min_size {
                let (existing, id) = registry.get_or_create_id(container_sig, top_level);
                if ! existing {
                    for (_, typ) in &fields {
                        if let TypeSignature::Container(child_id) = typ {
                            registry.id_to_signature.get_mut(child_id).unwrap().parent_count += 1;
                        }
                    }
                }
                TypeSignature::Container(id)
            } else {
                TypeSignature::Verbatim(container_sig)
            }
        }
        List(l) => collect_sequence_signatures(
            l.into_iter(),
            registry,
            min_size,
            top_level,
            ContainerSignature::List,
        )?,
        SExp(s) => collect_sequence_signatures(
            s.into_iter(),
            registry,
            min_size,
            top_level,
            ContainerSignature::SExp,
        )?,
    })
}
