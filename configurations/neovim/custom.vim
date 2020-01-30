" ####################################
" # Languages Specific Configuration #
" ####################################

" Golang
" ======
" Use tabs instead of spaces for indentation.
autocmd FileType go :set noexpandtab
" Don't display tab indentation.
set nolist

" Markdown
" ========
" Set the max line length to be able to use two windows on laptop screens.
autocmd FileType markdown :set textwidth=79

" Asciidoctor
" ===========
autocmd FileType asciidoc :set textwidth=79

" Python
" ======
" Set the line length according to PEP8.
" No new line is created automatically when reaching the maximum length,
" as this is rather annoying.
autocmd FileType python :set colorcolumn=80
" Check code syntax before saving file.
autocmd BufWritePost *.py call Flake8()
" Shortcut for inserting a breakpoint.
au FileType python map <silent> <leader>s oimport pdb<CR>pdb.set_trace()<esc>

" YAML
" ====
" Set the indentation to 2 spaces.
autocmd FileType yaml :set shiftwidth=2 tabstop=2
