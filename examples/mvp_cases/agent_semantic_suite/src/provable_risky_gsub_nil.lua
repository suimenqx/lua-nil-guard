local function normalize_tag()
  local tag = nil
  return string.gsub(tag, "^guest", "member")
end

return {
  normalize_tag = normalize_tag,
}
