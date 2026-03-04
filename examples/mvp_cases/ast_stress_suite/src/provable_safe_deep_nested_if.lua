local username = req.params.username

if req.ready then
  if req.authenticated then
    if req.region_ok then
      if req.feature_flag then
        if req.cache_ready then
          if req.profile_loaded then
            if req.audit_ok then
              if username then
                return string.match(username, "^a")
              end
            end
          end
        end
      end
    end
  end
end
