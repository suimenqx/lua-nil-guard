local function scan_items(req)
  local items = req.items or {}
  for _, item in pairs(items) do
    return item
  end
  return nil
end

return {
  scan_items = scan_items,
}
