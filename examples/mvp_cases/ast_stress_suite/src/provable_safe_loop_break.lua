local username = req.params.username

while true do
  if not username then
    break
  end
  return string.match(username, "^a")
end
