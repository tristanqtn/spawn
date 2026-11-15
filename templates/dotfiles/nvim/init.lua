-- neovim, no plugin manager, so the env starts instantly.
-- This directory is copied in writable, so a plugin manager can write its lockfile
-- here if you add one later.
vim.opt.number = true
vim.opt.relativenumber = true
vim.opt.expandtab = true
vim.opt.shiftwidth = 2
vim.opt.tabstop = 2
vim.opt.ignorecase = true
vim.opt.smartcase = true
vim.opt.termguicolors = true
vim.opt.clipboard = "unnamedplus"
vim.opt.undofile = true
-- Undo history under the persisted state directory, so it survives spawn rm.
vim.opt.undodir = "/root/.local/state/nvim-undo"

-- Dracula-ish without a plugin: habamax is the closest built-in dark scheme.
pcall(vim.cmd.colorscheme, "habamax")

vim.g.mapleader = " "
vim.keymap.set("n", "<leader>w", "<cmd>w<cr>")
vim.keymap.set("n", "<leader>q", "<cmd>q<cr>")
vim.keymap.set("n", "<esc>", "<cmd>nohlsearch<cr>")
