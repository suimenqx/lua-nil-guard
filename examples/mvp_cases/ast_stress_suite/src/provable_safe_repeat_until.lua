local username = nil

repeat
  username = req.params.username
until username

return string.match(username, "^a")
