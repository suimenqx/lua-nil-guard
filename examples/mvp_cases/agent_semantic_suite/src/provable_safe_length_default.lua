local function count_items(req)
  local items = req.items or {}
  return #items
end

return {
  count_items = count_items,
}
