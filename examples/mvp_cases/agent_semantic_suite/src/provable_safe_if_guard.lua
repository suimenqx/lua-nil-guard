local function parse_guarded(req)
  local nickname = req.params.nickname
  if nickname then
    return string.match(nickname, "^vip")
  end
  return nil
end

return {
  parse_guarded = parse_guarded,
}
