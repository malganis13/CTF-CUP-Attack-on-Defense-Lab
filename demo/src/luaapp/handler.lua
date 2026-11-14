-- Demo fixture: deliberately vulnerable. Never executed.
local handler = {}

function handler.run(args)
    local code = args.code
    local fn = loadstring(code)
    if fn then fn() end
    os.execute("date")
end

return handler
