--[[
  json_pure.lua - Pure Lua JSON encoder & decoder for ZySentinel WAF
  Provides safe fallback when cjson.so binary is not available.
]]

local json = {}

local function kind_of(obj)
  if type(obj) ~= 'table' then return type(obj) end
  local i = 1
  for _ in pairs(obj) do
    if obj[i] ~= nil then i = i + 1 else return 'table' end
  end
  if i == 1 then return 'table' else return 'array' end
end

local function escape_str(s)
  local in_char  = {'\\', '"', '/', '\b', '\f', '\n', '\r', '\t'}
  local out_char = {'\\\\', '\\"', '\\/', '\\b', '\\f', '\\n', '\\r', '\\t'}
  for i, c in ipairs(in_char) do
    s = s:gsub(c, out_char[i])
  end
  return s
end

-- Stringify
function json.encode(val)
  local t = type(val)
  if t == 'nil' then
    return 'null'
  elseif t == 'boolean' then
    return val and 'true' or 'false'
  elseif t == 'number' then
    return tostring(val)
  elseif t == 'string' then
    return '"' .. escape_str(val) .. '"'
  elseif t == 'table' then
    local kind = kind_of(val)
    local res = {}
    if kind == 'array' then
      for _, v in ipairs(val) do
        table.insert(res, json.encode(v))
      end
      return '[' .. table.concat(res, ',') .. ']'
    else
      for k, v in pairs(val) do
        if type(k) == 'string' or type(k) == 'number' then
          table.insert(res, '"' .. escape_str(tostring(k)) .. '":' .. json.encode(v))
        end
      end
      return '{' .. table.concat(res, ',') .. '}'
    end
  else
    return '"' .. tostring(val) .. '"'
  end
end

-- Parser
local function skip_whitespace(str, idx)
  return str:match('^%s*()', idx)
end

local parse_value

local function parse_string(str, idx)
  local i = idx + 1
  local res = {}
  local len = #str
  while i <= len do
    local c = str:sub(i, i)
    if c == '"' then
      return table.concat(res), i + 1
    elseif c == '\\' then
      local next_c = str:sub(i + 1, i + 1)
      if next_c == '"' or next_c == '\\' or next_c == '/' then
        table.insert(res, next_c)
        i = i + 2
      elseif next_c == 'b' then table.insert(res, '\b'); i = i + 2
      elseif next_c == 'f' then table.insert(res, '\f'); i = i + 2
      elseif next_c == 'n' then table.insert(res, '\n'); i = i + 2
      elseif next_c == 'r' then table.insert(res, '\r'); i = i + 2
      elseif next_c == 't' then table.insert(res, '\t'); i = i + 2
      elseif next_c == 'u' then
        local hex = str:sub(i + 2, i + 5)
        local cp = tonumber(hex, 16)
        if cp then
          if cp < 128 then
            table.insert(res, string.char(cp))
          else
            table.insert(res, '?')
          end
          i = i + 6
        else
          table.insert(res, '\\u')
          i = i + 2
        end
      else
        table.insert(res, next_c)
        i = i + 2
      end
    else
      table.insert(res, c)
      i = i + 1
    end
  end
  return table.concat(res), i
end

local function parse_number(str, idx)
  local num_str = str:match('^[%-%+]?%d+%.?%d*[eE]?[%-%+]?%d*', idx)
  if num_str then
    return tonumber(num_str), idx + #num_str
  end
  return nil, idx
end

local function parse_array(str, idx)
  local arr = {}
  idx = idx + 1
  while true do
    idx = skip_whitespace(str, idx)
    if idx > #str then break end
    if str:sub(idx, idx) == ']' then
      return arr, idx + 1
    end
    local val
    val, idx = parse_value(str, idx)
    table.insert(arr, val)
    idx = skip_whitespace(str, idx)
    local c = str:sub(idx, idx)
    if c == ']' then
      return arr, idx + 1
    elseif c == ',' then
      idx = idx + 1
    else
      break
    end
  end
  return arr, idx
end

local function parse_object(str, idx)
  local obj = {}
  idx = idx + 1
  while true do
    idx = skip_whitespace(str, idx)
    if idx > #str then break end
    if str:sub(idx, idx) == '}' then
      return obj, idx + 1
    end
    if str:sub(idx, idx) ~= '"' then
      break
    end
    local key
    key, idx = parse_string(str, idx)
    idx = skip_whitespace(str, idx)
    if str:sub(idx, idx) == ':' then
      idx = idx + 1
    end
    local val
    val, idx = parse_value(str, idx)
    if key ~= nil then obj[key] = val end
    idx = skip_whitespace(str, idx)
    local c = str:sub(idx, idx)
    if c == '}' then
      return obj, idx + 1
    elseif c == ',' then
      idx = idx + 1
    else
      break
    end
  end
  return obj, idx
end

parse_value = function(str, idx)
  idx = skip_whitespace(str, idx)
  if idx > #str then return nil, idx end
  local c = str:sub(idx, idx)
  if c == '"' then
    return parse_string(str, idx)
  elseif c == '{' then
    return parse_object(str, idx)
  elseif c == '[' then
    return parse_array(str, idx)
  elseif str:sub(idx, idx + 3) == 'true' then
    return true, idx + 4
  elseif str:sub(idx, idx + 4) == 'false' then
    return false, idx + 5
  elseif str:sub(idx, idx + 3) == 'null' then
    return nil, idx + 4
  else
    return parse_number(str, idx)
  end
end

function json.decode(str)
  if type(str) ~= 'string' or str == '' then return nil end
  local val, _ = parse_value(str, 1)
  return val
end

return json
