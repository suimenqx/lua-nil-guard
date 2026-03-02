local function collect_names(req)
  local names = req.names or {}
  table.insert(names, "guest")
  return names
end

return {
  collect_names = collect_names,
}
