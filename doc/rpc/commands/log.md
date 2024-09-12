```
log "category|all" "on|off"
Turn categories on or off

With no arguments it returns a list of currently on log categories

Arguments:
1. "category|all" (string, required) Category or all categories
2. "on"           (string, optional) Turn a category, or all categories, on
2. "off"          (string, optional) Turn a category, or all categories, off
2.                (string, optional) No argument. Show a category, or all categories, state: on|off
> nexa-cli log "NET" on
> nexa-cli log "all" off
> nexa-cli log "tor" 
> nexa-cli log "ALL" 
> nexa-cli log  

```
