set nocompatible	"be iMproved
filetype off		" required!

" Setting up Vundle - the vim plugin bundler
let iCanHazVundle=1
let vundle_readme=expand('~/.vim/bundle/vundle/README.md')
if !filereadable(vundle_readme)
	echo "Installing Vundle.."
	echo ""
	silent !mkdir -p ~/.vim/bundle
	silent !git clone https://github.com/gmarik/vundle ~/.vim/bundle/vundle
	let iCanHazVundle=0
endif

set rtp+=~/.vim/bundle/vundle
call vundle#rc()

" Let Vundle manage Vundle
" required!
" Install command :BundleInstall
Bundle 'gmarik/vundle'

" My bundle
Bundle 'Lokaltog/vim-easymotion'
Bundle 'airblade/vim-gitgutter'
Bundle 'scrooloose/nerdtree'
Bundle 'Townk/vim-autoclose'
Bundle 'brookhong/cscope.vim'
Bundle 'tpope/vim-fugitive'
Bundle 'taglist.vim'
" Bundle 'tpope/vim-afterimage'
" Bundle 'Lokaltog/vim-powerline'


" general
set ruler
set history=50
set showmode
set shiftwidth=4
set tabstop=4
set noexpandtab
set incsearch
set number
set hls
set sw=4
set guifontset=8x16,kc15f,-*-16-*-big5-0 
set cursorline
set ignorecase
set ls=2
set fileformats=dos,unix

" show :tabe file name
set wildmenu

" highlight tab as >--- (gray)
set listchars=tab:>-
" set list
hi SpecialKey ctermfg=7 guifg=gray
" F2 toggle list
map <F2> :set list! list? <CR>
" F5 enalbe line number
map <F5> :set number! number? <CR>
" F6 change binary file to txt
map <F6> :%!xxd  <CR>
" F7 change txt file to binary
map <F7> :%!xxd -r <CR>
" F8 remove all trailing whitespace
nnoremap <silent> <F8> :let _s=@/<Bar>:%s/\s\+$//e<Bar>:let @/=_s<Bar>:nohl<CR>

"clipboard
"set clipboard=unnamedplus
"vnoremap y "+y
"vnoremap y "*y
"vnoremap p "+p

"set fenc=big5 enc=big5 tenc=utf8
syntax on
highlight Comment ctermfg=darkcyan
highlight Search term=reverse ctermbg=4 ctermfg=7
highlight CursorLine cterm=none ctermbg=darkred ctermfg=white
set background=dark
if has("autocmd")
   autocmd BufRead *.txt set tw=78
   autocmd BufReadPost *
      \ if line("'\"") > 0 && line ("'\"") <= line("$") |
      \   exe "normal g'\"" |
      \ endif
endif
imap <C-F11> <C-R>=strftime("%x %X")<BAR><CR>. owen_wen@htc.com.<ESC> <C-R>

" F4 enable taglist
nnoremap <F4> :TlistToggle<CR>
" map <F4> :silent! Tlist<CR>

let Tlist_Exit_OnlyWindow=1
let Tlist_Show_One_File=1
filetype plugin on
"let g:neocomplcache_enable_at_startup = 1 

" vim-gitgutter
let g:gitgutter_enabled = 1
highlight clear SignColumn " For the same appearance as your line unmber column

" F3 open sidebar
nnoremap <F3> :silent! NERDTreeToggle<CR>
let g:NERDTreeWinPos = "right"

" powerline
"let g:Poerline_symbols = 'fancy' " require fontpatcher

" cscope
if has('cscope')
   set cscopetag cscopeverbose

   if has('quickfix')
      set cscopequickfix=s-,c-,d-,i-,t-,e-
   endif
   if filereadable("cscope.out")
      cs add cscope.out
   endif

   cnoreabbrev csa cs add
   cnoreabbrev csf cs find
   cnoreabbrev csk cs kill
   cnoreabbrev csr cs reset
   cnoreabbrev css cs show
   cnoreabbrev csh cs help

   nmap \cfs :cs find s <C-R>=expand("<cword>")<CR><CR>
   nmap \cfc :cs find c <C-R>=expand("<cword>")<CR><CR>

"   command -nargs=0 Cscope cs add $VIMSRC/src/cscope.out $VIMSRC/src
endif

" Tab key binding
  map <C-p>  :tabepre<CR>
  map <C-n>  :tabenext<CR>

  map g1 :tabn 1<CR>
  map g2 :tabn 2<CR>
  map g3 :tabn 3<CR>
  map g4 :tabn 4<CR>
  map g5 :tabn 5<CR>
  map g6 :tabn 6<CR>
  map g7 :tabn 7<CR>
  map g8 :tabn 8<CR>
  map g9 :tabn 9<CR>

  highlight TabLineSel term=bold,underline cterm=bold,underline ctermfg=7 ctermbg=1
  highlight TabLine term=underline cterm=underline ctermfg=7 ctermbg=0
  highlight clear TabLineFill
