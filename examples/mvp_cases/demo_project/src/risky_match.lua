local function parse_username(req)
  local username = req.params.username
  return string.match(username, "^admin")
end

return {
  parse_username = parse_username,
}
