local function parse_defaulted(req)
  local display_name = req.params.display_name or ""
  return string.match(display_name, "^guest")
end

return {
  parse_defaulted = parse_defaulted,
}
