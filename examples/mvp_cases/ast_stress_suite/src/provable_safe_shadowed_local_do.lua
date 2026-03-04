local username = req.params.username

if username then
  do
    local username = nil
    log(username)
  end
  return string.match(username, "^a")
end
