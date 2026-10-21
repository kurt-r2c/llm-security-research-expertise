# Object fetched by id without owner scope

Language: Ruby

## Vulnerable
```ruby
def show
  invoice = Invoice.find(params[:id])
  render json: invoice
end
```

## Fixed
```ruby
def show
  invoice = current_user.invoices.find(params[:id])
  render json: invoice
end
```

Invariant: A record reached by a client-supplied id must be looked up through the caller's own scope or checked against the caller.

Look for: Model.find/get/findOne keyed only by a request id in a handler that has an authenticated user available.
