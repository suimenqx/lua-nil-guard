local function scan_items(req)
  for _, item in pairs(req.items) do
    return item
  end
  return nil
end

return {
  scan_items = scan_items,
}
