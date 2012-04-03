class User < ActiveRecord::Base
  KEY   = "3a142e9425ebebca54ee5f959ed0dbba"
  IV    = "HtoGS7q5CZge2uGKCTBuyw=="
  require 'aes'

  devise :database_authenticatable, :confirmable, :lockable, :recoverable,
         :rememberable, :registerable, :trackable, :timeoutable, :validatable,
         :token_authenticatable

  attr_accessible :email, :password, :password_confirmation

  def email_before_type_cast
    super.present? ? AES.decrypt(super, KEY) : ""
  end

  def email
    return "" unless self[:email]
    @email ||= AES.decrypt(self[:email], KEY)
  end

  def email=(provided_email)
    self[:email] = encrypted_email(provided_email)
    @email = provided_email
  end

  def email_was
    super.present? ? AES.decrypt(super, KEY) : ""
  end

  def self.find_for_authentication(conditions={})
    conditions[:email] = encrypted_email(conditions[:email])
    super
  end

  def self.find_or_initialize_with_errors(required_attributes, attributes, error=:invalid)
    attributes[:email] = encrypted_email(attributes[:email]) if attributes[:email]
    super
  end

  def self.encrypted_email decrypted_email
    AES.encrypt(decrypted_email, KEY, {:iv => IV})
  end

  def find_by_unconfirmed_email_with_errors(attributes = {})
    attributes[:email] = encrypted_email(attributes[:email]) if attributes[:email]
    super
  end

  private

  def encrypted_email(decrypted_email)
    self.class.encrypted_email(decrypted_email)
  end

end
