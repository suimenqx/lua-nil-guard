local function parse_literal()
  local username = nil
  return string.match(username, "^admin")
end

return {
  parse_literal = parse_literal,
}
