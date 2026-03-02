local function append_name(req)
  table.insert(req.names, "guest")
  return req.names
end

return {
  append_name = append_name,
}
