" ####################################
" # Languages specific configuration #
" ####################################

" Python
" ======
" Set the max line length according to PEP8.
autocmd FileType python :set textwidth=79
" Check code syntax before saving file.
autocmd BufWritePost *.py call Flake8()
" Shortcut for inserting a breakpoint.
au FileType python map <silent> <leader>s oimport pdb<CR>pdb.set_trace()<esc>

" YAML
" ====
" Set the indentation to 2 spaces.
autocmd FileType yaml :set shiftwidth=2 tabstop=2
