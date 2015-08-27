" #########################
" # Plugins configuration #
" #########################
call plug#begin()
Plug 'airblade/vim-gitgutter'
Plug 'bling/vim-airline'
Plug 'kien/ctrlp.vim'
Plug 'nvie/vim-flake8'
Plug 'scrooloose/nerdtree'
Plug 'sickill/vim-monokai'
call plug#end()

" CtrlP
" =====
" Maximum number of files to scan.
let g:ctrlp_max_files = 100000
" Command to use to find files in directories versionned with Git.
let g:ctrlp_user_command = ['.git', 'cd %s && git ls-files']


" ######################
" # Keyboard shortcuts #
" ######################

" General
" =======
" Display buffers (plugin CtrlP).
map <C-b> :CtrlPBuffer<CR>

" Tree panel
" ==========
" Open or close the three panel (plugin NERD Tree).
map <C-n> :NERDTreeToggle<CR>
" Find the current file in the tree panel (plugin NERD Tree).
map <C-f> :NERDTreeFind<CR>


" ########################
" # Global configuration #
" ########################

" Layout
" ======
" Show the status bar as the second last line in the editor window.
set laststatus=2

" Displaying
" ==========
" Enable syntax colorization.
syntax enable
" Use Monokai theme.
colorscheme monokai
" Display line numbers.
set number
" Display tabs and spaces.
set list
" Characters used to display tabs and spaces.
set listchars=tab:>.,trail:.
" Highlight column after maximum text width.
set cc=+1

" Editing
" =======
" Replace tabs by spaces.
set expandtab
" Number of spaces to use for indentation.
set shiftwidth=4
" Number of spaces to use for tabulations (not for indentation).
set tabstop=4


" ####################################
" # Languages specific configuration #
" ####################################

" Python
" ======
" Set the max line length.
autocmd FileType python :set textwidth=120
" Check code syntax before saving file.
autocmd BufWritePost *.py call Flake8()
