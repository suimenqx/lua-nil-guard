local function normalize_pair(name)
  name = name or "guest"
  return name, "fallback"
end

local function parse_pair(req)
  local display_name, tag = normalize_pair(req.params.display_name)
  return string.match(display_name, "^g")
end

return {
  parse_pair = parse_pair,
}
