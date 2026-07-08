-- Custom processing for the concatenated PDF/ODT build (see
-- TeX/Makefile's MD_SRC): ipacta-comprehensive.md followed by the
-- appendix divider and each module-reference file, each of which
-- starts with its own top-level (H1) heading.
--
--  1. Force a page break before every H1 except the first, so each
--     appended file starts on a fresh page.
--  2. Make long inline code spans breakable at identifier/path/
--     camelCase boundaries, since plain \texttt text never wraps on
--     its own -- long function signatures, DNs, and path templates
--     were overflowing their table column (or, outside tables,
--     running off the page margin entirely).
--  3. Replace Unicode box-drawing characters in fenced code blocks
--     (the ASCII-art tree/state diagrams) with plain ASCII, since
--     pdflatex's default fonts don't have those glyphs.
--  4. Recompute table column widths from actual cell content. Pandoc
--     sizes pipe-table columns from the header row's text width, not
--     the body -- a short header like "Parameter" over a column full
--     of long values ends up with most of the table's width, leaving
--     the actual long content squeezed into a narrow column full of
--     awkward wraps. This runs as its own pass, before the Code
--     rewrite below, so it measures the original cell text.

-- No column drops below this share of the table width, however short
-- its content -- otherwise a "Parameter"/"Method"-style header column
-- next to a column full of paragraph-length values gets so little
-- room that even the header word itself has to wrap.
local MIN_COL_FRACTION = 0.2

local function measure_colwidths(el)
  local ncols = #el.colspecs
  local maxlen = {}
  for i = 1, ncols do maxlen[i] = 1 end

  local function measure_row(row)
    for i, cell in ipairs(row.cells) do
      local len = #pandoc.utils.stringify(cell)
      if len > maxlen[i] then maxlen[i] = len end
    end
  end

  for _, row in ipairs(el.head.rows) do measure_row(row) end
  for _, body in ipairs(el.bodies) do
    for _, row in ipairs(body.body) do measure_row(row) end
  end

  -- sqrt compresses the raw length ratio: a column with 150 characters
  -- of content shouldn't get 18x the width of one with 8, just more.
  local weight = {}
  local total = 0
  for i = 1, ncols do
    weight[i] = math.sqrt(maxlen[i])
    total = total + weight[i]
  end

  local frac = {}
  for i = 1, ncols do
    frac[i] = weight[i] / total
  end
  if ncols * MIN_COL_FRACTION < 1 then
    for i = 1, ncols do
      if frac[i] < MIN_COL_FRACTION then
        frac[i] = MIN_COL_FRACTION
      end
    end
    local newtotal = 0
    for i = 1, ncols do newtotal = newtotal + frac[i] end
    for i = 1, ncols do frac[i] = frac[i] / newtotal end
  end

  local newspecs = {}
  for i = 1, ncols do
    newspecs[i] = {el.colspecs[i][1], frac[i]}
  end
  el.colspecs = newspecs
  return el
end

local seen_h1 = false

local function Header(el)
  if el.level == 1 then
    if seen_h1 then
      return {pandoc.RawBlock('latex', '\\clearpage'), el}
    end
    seen_h1 = true
  end
  return el
end

local function latex_escape(s)
  s = s:gsub('\\', '\\textbackslash{}')
  s = s:gsub('{', '\\{')
  s = s:gsub('}', '\\}')
  s = s:gsub('_', '\\_')
  s = s:gsub('#', '\\#')
  s = s:gsub('%%', '\\%%')
  s = s:gsub('&', '\\&')
  s = s:gsub('%$', '\\$')
  s = s:gsub('~', '\\textasciitilde{}')
  s = s:gsub('%^', '\\textasciicircum{}')
  return s
end

-- Split on identifier/path separators (and camelCase word boundaries,
-- for the Java-style plugin class names in the profile tables, which
-- have no separator characters at all), escape each segment, and glue
-- them back together with \allowbreak so the whole span can still
-- wrap even though none of its individual characters are spaces.
local function breakable_code(text)
  local parts = {}
  local current = ''
  for i = 1, #text do
    local c = text:sub(i, i)
    local prev = current:sub(-1)
    if current ~= '' and prev:match('%l') and c:match('%u') then
      table.insert(parts, current)
      current = ''
    end
    current = current .. c
    if c:match('[_./,=:%-]') then
      table.insert(parts, current)
      current = ''
    end
  end
  if current ~= '' then
    table.insert(parts, current)
  end
  local escaped = {}
  for _, p in ipairs(parts) do
    table.insert(escaped, latex_escape(p))
  end
  return '\\texttt{' .. table.concat(escaped, '\\allowbreak{}') .. '}'
end

local function Code(el)
  return pandoc.RawInline('latex', breakable_code(el.text))
end

local box_drawing_map = {
  ['─'] = '-', ['│'] = '|', ['┌'] = '+', ['┐'] = '+',
  ['└'] = '+', ['┘'] = '+', ['├'] = '+', ['┤'] = '+',
  ['┬'] = '+', ['┴'] = '+', ['┼'] = '+',
}

local function CodeBlock(el)
  local text = el.text
  for uni, ascii in pairs(box_drawing_map) do
    text = text:gsub(uni, ascii)
  end
  el.text = text
  return el
end

-- Two sequential passes: table column widths must be measured from
-- the original cell text before Code turns it into raw LaTeX (which
-- stringify can't measure), so that pass runs first.
return {
  {Table = measure_colwidths},
  {Header = Header, Code = Code, CodeBlock = CodeBlock},
}
