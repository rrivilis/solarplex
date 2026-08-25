-- wezterm.lua — Solarplex integration for WezTerm
--
-- Copy or symlink to: ~/.wezterm.lua   (or merge into your existing config)
-- Docs: https://wezfurlong.org/wezterm/config/files.html

local wezterm = require 'wezterm'
local config  = wezterm.config_builder()

-- ── Default shell: WSL (fish) ────────────────────────────────────────────────
-- Opens new tabs/windows directly into WSL running fish.
-- Change 'Ubuntu' to your distro name if different (wsl -l -v to check).
config.default_prog = { 'wsl.exe', '--distribution', 'Ubuntu', '--', 'fish' }

-- ── Shell integration (OSC-133) ───────────────────────────────────────────────
-- Enables semantic zones so WezTerm can jump between prompts (Ctrl+Shift+Up/Down),
-- select command output regions, and show the exit code in the right-click menu.
config.enable_scroll_bar = true
config.scrollback_lines  = 10000

-- ── URI handler for solarplex: links ─────────────────────────────────────────
-- WezTerm calls this function when the user clicks an OSC-8 hyperlink.
-- Any URI whose scheme is "solarplex" gets routed through `sp plumb`.
--
-- After running `sp _install_uri_handler` inside WSL, xdg-open handles it.
-- This wezterm handler is the primary path for in-terminal clicks.
--
-- Protocol: clicking "solarplex:artifact/01J..." in a WezTerm pane invokes:
--   wsl sp plumb run solarplex:artifact/01J...
--
wezterm.on('open-uri', function(window, pane, uri)
  if uri:match('^solarplex:') then
    -- Route through sp plumb inside WSL. --untrusted: this fires from a
    -- click on rendered pane content, which may not be operator-typed (same
    -- threat model as the OS URI handler) -- skips plumb.toml user rules
    -- and refuses act/ (state-mutating) targets. Contrast with the Alt+Enter
    -- binding below, which plumbs text the operator explicitly selected.
    local cmd = { 'wsl', 'sp', 'plumb', 'run', '--untrusted', uri }
    wezterm.background_child_process(cmd)
    -- Return true to suppress WezTerm's default open-uri handling
    return true
  end
  -- Return nil / false to fall through to default (open in browser)
end)

-- ── Keyboard shortcuts ────────────────────────────────────────────────────────
-- Alt+Enter: plumb the selected text (or word under cursor) via sp plumb.
-- Fish already handles Alt+Enter at the prompt; this catches it in output
-- regions where there's no readline.
config.keys = {
  -- Ctrl+Shift+Space: open WezTerm command palette (nice to have)
  { key = 'Space', mods = 'CTRL|SHIFT', action = wezterm.action.ActivateCommandPalette },

  -- Ctrl+Shift+P: jump to previous prompt (OSC-133 required)
  { key = 'UpArrow', mods = 'CTRL|SHIFT',
    action = wezterm.action.ScrollToPrompt(-1) },
  { key = 'DownArrow', mods = 'CTRL|SHIFT',
    action = wezterm.action.ScrollToPrompt(1) },

  -- Alt+Enter: plumb selected text (or URI under mouse) via sp
  { key = 'Return', mods = 'ALT',
    action = wezterm.action_callback(function(window, pane)
      local sel = window:get_selection_text_for_pane(pane)
      if sel and sel ~= '' then
        local cmd = { 'wsl', 'sp', 'plumb', 'run', sel:gsub('%s+', '') }
        wezterm.background_child_process(cmd)
      end
    end)
  },
}

-- ── Tab title: show Solarplex session ID ──────────────────────────────────────
-- Reads the SOLARPLEX_SESSION_ID user var set by `sp _shell setvar` (OSC-1337).
-- Falls back to the default tab title when no session is attached.
wezterm.on('format-tab-title', function(tab, tabs, panes, cfg, hover, max_width)
  local pane = tab.active_pane
  local vars = pane:get_user_vars()
  local sid  = vars.SOLARPLEX_SESSION_ID
  if sid and sid ~= '' then
    -- Show first 8 chars of the session ULID
    local short = sid:sub(1, 8)
    return wezterm.format({
      { Attribute = { Intensity = 'Bold' } },
      { Text = '⬡ ' .. short .. ' ' },
    })
  end
  -- Default: process name
  return tab.active_pane.title
end)

-- ── Appearance (optional, minimal) ───────────────────────────────────────────
config.color_scheme = 'Tokyo Night'
config.font = wezterm.font('JetBrains Mono', { weight = 'Regular' })
config.font_size = 13.0
config.window_decorations = 'RESIZE'

return config
