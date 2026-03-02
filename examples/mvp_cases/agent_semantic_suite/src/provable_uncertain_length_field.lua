local function count_items(req)
  return #req.items
end

return {
  count_items = count_items,
}
