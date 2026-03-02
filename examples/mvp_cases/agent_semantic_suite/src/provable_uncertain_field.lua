local function parse_field(req)
  return string.match(req.params.username, "^guest")
end

return {
  parse_field = parse_field,
}
