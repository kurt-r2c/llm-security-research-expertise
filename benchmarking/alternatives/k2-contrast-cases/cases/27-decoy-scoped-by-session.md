# DECOY: id from the request but query scoped to caller

Language: Ruby

## Looks vulnerable
```ruby
def destroy
  doc = Document.where(owner_id: current_user.id).find(params[:id])
  doc.destroy
  head :no_content
end
```

Superficially identical to the IDOR shape, but the where() clause binds the owner. A reader who greps only for find(params[:id]) will misreport it.

Invariant: Ownership is part of the query itself, so another user's id yields not-found.

Look for: A request-supplied id is safe when the lookup is composed with the caller's identity; look at the whole chain, not just find(params[:id]).
