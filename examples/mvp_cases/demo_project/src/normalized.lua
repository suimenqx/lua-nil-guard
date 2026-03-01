local function normalize_name(name)
  name = name or ""
  return name
end

local function parse_display_name(req)
  local display_name = normalize_name(req.params.display_name)
  return string.match(display_name, "^guest")
end

return {
  normalize_name = normalize_name,
  parse_display_name = parse_display_name,
}
