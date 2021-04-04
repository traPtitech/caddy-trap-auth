# caddy-trap-auth

## usage
```
trapauth
trapauth {
    redirect [location]
    token_source [header or cookie]
    source_key [cookie name]
    type [soft or hard]
    user_header [name]
    accept_user [username] [username]
    no_strip
    invalidate_token [token] [token]
}
```
