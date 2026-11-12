//! Native byte-oriented Goldmark 1.8.6 implementation for the Caddy pipeline.
//! Fixed GFM + Footnote + automatic heading IDs + unsafe HTML configuration.
//! Parser, transforms, renderer and Chroma share the request allocation owner.
use super::allocation;
mod ast;
mod autolinks;
mod block_reader;
mod blocks;
mod case_folding;
mod delimiters;
mod entities;
mod footnotes;
mod html_parser;
mod html_render;
mod ids;
mod inlines;
mod list_parser;
mod normalize;
mod output;
mod parse_util;
mod parser;
mod punctuation;
mod reader;
mod references;
mod segment;
mod table_parser;
mod tables;
mod text;
mod text_writer;

pub(super) fn convert(
    input: &[u8],
    account: &gotmpl::BudgetAccount,
    highlight: impl FnMut(&[u8], &[u8]) -> gotmpl::Result<Option<gotmpl::BudgetedBytes>>,
) -> gotmpl::Result<gotmpl::BudgetedBytes> {
    let (mut arena, root) = parser::Parser::new(input, account).parse()?;
    html_render::render(&mut arena, root, input, 1 << 20, highlight)
}
