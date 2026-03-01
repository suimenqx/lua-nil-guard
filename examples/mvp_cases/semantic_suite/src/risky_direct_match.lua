local function parse_direct(req)
  return string.match(req.params.username, "^root")
end

return {
  parse_direct = parse_direct,
}
