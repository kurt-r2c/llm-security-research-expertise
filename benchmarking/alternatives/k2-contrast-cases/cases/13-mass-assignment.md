# Whole request hash assigned to a model

Language: Ruby

## Vulnerable
```ruby
def update
  current_user.update!(params[:user])  # includes role, admin, org_id
  head :ok
end
```

## Fixed
```ruby
def update
  current_user.update!(params.require(:user).permit(:name, :email))
  head :ok
end
```

Invariant: Only an explicit allow-list of fields may be written from client input; privilege and ownership columns are server-set.

Look for: update/create/assign/Object.assign/spread of req.body or params straight into a model, ORM entity or settings object.
