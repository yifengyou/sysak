use anyhow::anyhow;
use anyhow::Result;
use std::ops::Range;
use tree_sitter;
use tree_sitter_c;
use std::ffi::CString;

#[derive(PartialEq, Debug, Clone)]
#[repr(u32)]
#[allow(non_camel_case_types)]
enum Ast {
    identifier = 1,
    lparen = 5,
    rparen = 8,
    star = 23,
    semi = 39,
    lbrack = 61,
    rbrack = 62,
    struct_ = 78,
    dot = 107,
    number_literal = 109,
    translation_unit = 128,
    abstract_pointer_declarator = 178,
    struct_specifier = 195,
    expression_statement = 208,
    cast_expression = 227,
    type_descriptor = 228,
    subscript_expression = 230,
    field_expression = 233,
    parenthesized_expression = 235,
    field_identifier = 267,
    type_identifier = 269,
}

impl Ast {
    pub fn from_u16(val: u16) -> Result<Ast> {
        match val {
            1 => Ok(Ast::identifier),
            5 => Ok(Ast::lparen),
            8 => Ok(Ast::rparen),
            23 => Ok(Ast::star),
            39 => Ok(Ast::semi),
            61 => Ok(Ast::lbrack),
            62 => Ok(Ast::rbrack),
            78 => Ok(Ast::struct_),
            107 => Ok(Ast::dot),
            109 => Ok(Ast::number_literal),
            128 => Ok(Ast::translation_unit),
            178 => Ok(Ast::abstract_pointer_declarator),
            195 => Ok(Ast::struct_specifier),
            208 => Ok(Ast::expression_statement),
            227 => Ok(Ast::cast_expression),
            228 => Ok(Ast::type_descriptor),
            230 => Ok(Ast::subscript_expression),
            233 => Ok(Ast::field_expression),
            235 => Ok(Ast::parenthesized_expression),
            267 => Ok(Ast::field_identifier),
            269 => Ok(Ast::type_identifier),
            _ => Err(anyhow!("unable to transmit u16({}) to Ast", val)),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum CastType {
    Struct(CString),
    Invalid,
}

#[derive(Debug, Clone)]
pub struct Cast {
    pub ct: CastType,
    pub pointer: i32,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub ident: CString,
    pub cast: Option<Cast>,
    pub index: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Parser {
    fields: Vec<Field>,
    // parser context
    expr: String,
    cast: Cast,
}

impl Parser {
    pub fn new() -> Parser {
        Parser {
            fields: Vec::new(),
            expr: String::default(),
            cast: Cast {
                ct: CastType::Invalid,
                pointer: 0,
            },
        }
    }

    pub fn parse(&mut self, expr: &String) -> Result<Vec<Field>>{
        self.fields.clear();
        self.expr = expr.clone();
        self.cast.ct = CastType::Invalid;
        self.cast.pointer = 0;

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(tree_sitter_c::language())
            .expect("Error loading C grammar");
        if let Some(parsed) = parser.parse(expr, None) {
            let walker = parsed.walk();
            self.visitor(walker.node())?;
        }

        Ok(self.fields.clone())
    }

    fn range_to_str(&self, range: Range<usize>) -> CString {
        CString::new(self.expr[range].to_owned()).expect("CString new failed")
    }

    fn visitor(&mut self, node: tree_sitter::Node) -> Result<()> {
        for child in 0..node.child_count() {
            let cd = node.child(child);
            if let Some(x) = cd {
                self.visitor(x)?;
            }
        }

        let ty = Ast::from_u16(node.kind_id())?;
        match ty {
            Ast::number_literal => {
                let mut index: Option<i32> = None;
                if let Some(_) = self.fields.last_mut() {
                    index = Some(self.range_to_str(node.byte_range()).into_string().expect("CString new failed").parse()?);
                }
                if let Some(item) = self.fields.last_mut() {
                    item.index = index;
                }
            }
            Ast::identifier => self.fields.push(Field {
                ident: self.range_to_str(node.byte_range()),
                cast: None,
                index: None,
            }),
            Ast::field_identifier => self.fields.push(Field {
                ident: self.range_to_str(node.byte_range()),
                cast: None,
                index: None,
            }),
            Ast::cast_expression => {
                if let Some(item) = self.fields.last_mut() {
                    item.cast = Some(self.cast.clone());
                }
                self.cast.ct = CastType::Invalid;
                self.cast.pointer = 0;
            }
            Ast::struct_ => self.cast.ct = CastType::Struct(CString::default()),
            Ast::type_identifier => match &self.cast.ct {
                CastType::Struct(_) => {
                    self.cast.ct = CastType::Struct(self.range_to_str(node.byte_range()))
                }
                CastType::Invalid => {
                    return Err(anyhow!(
                        "unknow cast type for type_identifier: {:?}",
                        self.range_to_str(node.byte_range())
                    ))
                }
            },
            Ast::abstract_pointer_declarator => self.cast.pointer += 1,
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let code = "a.b.c;".to_owned();
        let p = Parser::new();
        println!("{:?}", p);
    }

    #[test]
    fn test_array_basic1() {
        let code = "a.b[2].c;".to_owned();
        let p = Parser::new();
        println!("{:?}", p);
    }
    #[test]
    fn test_array_basic2() {
        let code = "a[2].b.c;".to_owned();
        let p = Parser::new();
        println!("{:?}", p);
    }
    #[test]
    fn test_array_basic3() {
        let code = "a.b.c[2];".to_owned();
        let p = Parser::new();
        println!("{:?}", p);
    }

    #[test]
    fn test_cast_basic1() {
        let code = "((struct d *)a).b.c;".to_owned();
        let p = Parser::new();
        println!("{:?}", p);
    }

    #[test]
    fn test_cast_basic2() {
        let code = "((struct d *)a.b).c;".to_owned();
        let p = Parser::new();
        println!("{:?}", p);
    }
}
