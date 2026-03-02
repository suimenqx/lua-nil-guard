local function parse_branch(req)
  local username = req.force_nil and nil or "admin"
  return string.find(username, "^admin")
end

return {
  parse_branch = parse_branch,
}
