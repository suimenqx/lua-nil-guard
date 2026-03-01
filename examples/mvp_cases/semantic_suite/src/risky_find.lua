local function has_prefix(req)
  local nickname = req.params.nickname
  return string.find(nickname, "^vip")
end

return {
  has_prefix = has_prefix,
}
