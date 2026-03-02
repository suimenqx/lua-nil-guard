local function passthrough_name(name)
  return name
end

local function parse_wrapper(req)
  local display_name = passthrough_name(req.params.display_name)
  return string.match(display_name, "^guest")
end

return {
  passthrough_name = passthrough_name,
  parse_wrapper = parse_wrapper,
}
