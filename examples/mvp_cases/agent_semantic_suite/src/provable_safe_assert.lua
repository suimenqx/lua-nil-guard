local function parse_asserted(req)
  local token = req.params.token
  assert(token)
  return string.find(token, "^session")
end

return {
  parse_asserted = parse_asserted,
}
