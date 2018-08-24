# Pwsafe

Passwordsafe tools written in ruby, supports:
- [x] Decode PwsafeV3
- [ ] Encode PwsafeV3
- [ ] Decode PwsafeV4
- [ ] Encode PwsafeV4

## Installation

```ruby
gem 'pwsafe'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install pwsafe

## Usage

CLI:

```bash
$ pwsafe <pwsafefile> list
```

as a library:

```ruby
pw = Pwsafe::V3::Decoder.new
return unless pw.password_valid?(password)
puts pw.headers.inspect
puts pw.fields.inspect
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/fudanchii/pwsafe.
