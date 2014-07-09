require 'active_record'
require 'unix_crypt'
require 'bcrypt'
require 'phpass'
require 'openssl'

class CASino::ActiveRecordAuthenticator

  class AuthDatabase < ::ActiveRecord::Base
    self.abstract_class = true
  end

  # @param [Hash] options
  def initialize(options)
    @options = options

    eval <<-END
      class #{self.class.to_s}::#{@options[:table].classify} < AuthDatabase
        self.table_name = "#{@options[:table]}"
      end
    END

    @model = "#{self.class.to_s}::#{@options[:table].classify}".constantize
    @model.establish_connection @options[:connection]
  end

  def validate(username, password)
    @model.verify_active_connections!
    user = @model.send("find_by_#{@options[:username_column]}!", username)
    password_from_database = user.send(@options[:password_column])
    password_salt_from_database = user.send(@options[:password_salt_column])
    unless user.send(@options[:suspended_til_column]).nil?
      return false
    end
    if valid_password?(password, password_from_database, password_salt_from_database)
      { username: user.send(@options[:username_column]),
      extra_attributes: extra_attributes(user) }
    else
      false
    end

  rescue ActiveRecord::RecordNotFound
    false
  end

  private
  def valid_password?(password, password_from_database, password_salt_from_database)
    return false if password_from_database.blank?
    magic = password_from_database.split('$')[1]
    case magic
    when /\A2a?\z/
      valid_password_with_bcrypt?(password, password_from_database)
    when /\AH\z/, /\AP\z/
      valid_password_with_phpass?(password, password_from_database)
    when nil
      valid_password_with_pbkdf2_sha256?(password, password_from_database, password_salt_from_database)
    else
      valid_password_with_unix_crypt?(password, password_from_database)
    end
  end

  def valid_password_with_bcrypt?(password, password_from_database)
    password_with_pepper = password + @options[:pepper].to_s
    BCrypt::Password.new(password_from_database) == password_with_pepper
  end

  def valid_password_with_unix_crypt?(password, password_from_database)
    UnixCrypt.valid?(password, password_from_database)
  end

  def valid_password_with_phpass?(password, password_from_database)
    Phpass.new().check(password, password_from_database)
  end

  def valid_password_with_pbkdf2_sha256?(password, password_from_database, password_salt_from_database)
    digest = OpenSSL::Digest::SHA256.new
    len = digest.digest_length
    iter = 64000
    eql_time_cmp(OpenSSL::PKCS5.pbkdf2_hmac(password, password_salt_from_database, iter, len, digest), password_from_database.hex_to_bin)
  end

  def extra_attributes(user)
    attributes = {}
    extra_attributes_option.each do |attribute_name, database_column|
      attributes[attribute_name] = user.send(database_column)
    end
    attributes
  end

  def extra_attributes_option
    @options[:extra_attributes] || {}
  end
end

def eql_time_cmp(a, b)
  unless a.length == b.length
    return false
  end
  cmp = b.bytes.to_a
  result = 0
  a.bytes.each_with_index {|c,i|
    result |= c ^ cmp[i]
  }
  result == 0
end

class String
  def hex_to_bin
     self.scan(/../).map { |x| x.hex.chr }.join
  end
end
