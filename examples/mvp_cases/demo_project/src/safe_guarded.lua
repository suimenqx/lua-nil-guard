local function parse_nickname(req)
  local nickname = req.params.nickname
  if nickname then
    return string.match(nickname, "^vip")
  end
  return nil
end

return {
  parse_nickname = parse_nickname,
}
