require 'spec_helper'
require 'casino/activerecord_authenticator'

describe CASino::ActiveRecordAuthenticator do

  let(:pepper) { nil }
  let(:extra_attributes) {{ email: 'mail_address' }}
  let(:options) do
    {
      connection: {
        adapter: 'sqlite3',
        database: '/tmp/casino-test-auth.sqlite'
      },
      table: 'users',
      username_column: 'username',
      password_column: 'password',
      password_salt_column: 'password_salt',
      suspended_til_column: 'suspended_til',
      pepper: pepper,
      extra_attributes: extra_attributes
    }
  end

  subject { described_class.new(options) }

  before do
    subject # ensure everything is initialized

    ::ActiveRecord::Base.establish_connection options[:connection]

    ActiveRecord::Migration.suppress_messages do
      ActiveRecord::Schema.define do
        create_table :users do |t|
          t.string :username
          t.string :password
          t.string :password_salt
          t.string :suspended_til
          t.string :mail_address
        end
      end
    end

    described_class::User.create!(
      username: 'test',
      password: '$5$cegeasjoos$vPX5AwDqOTGocGjehr7k1IYp6Kt.U4FmMUa.1l6NrzD', # password: testpassword
      mail_address: 'mail@example.org')
  end

  after do
    ActiveRecord::Migration.suppress_messages do
      ActiveRecord::Schema.define do
        drop_table :users
      end
    end
  end

  describe '#validate' do

    context 'valid username' do
      context 'valid password' do
        it 'returns the username' do
          subject.validate('test', 'testpassword')[:username].should eq('test')
        end

        it 'returns the extra attributes' do
          subject.validate('test', 'testpassword')[:extra_attributes][:email].should eq('mail@example.org')
        end

        context 'when no extra attributes given' do
          let(:extra_attributes) { nil }

          it 'returns an empty hash for extra attributes' do
            subject.validate('test', 'testpassword')[:extra_attributes].should eq({})
          end
        end
      end

      context 'invalid password' do
        it 'returns false' do
          subject.validate('test', 'wrongpassword').should eq(false)
        end
      end

      context 'NULL password field' do
        it 'returns false' do
          user = described_class::User.first
          user.password = nil
          user.save!

          subject.validate('test', 'wrongpassword').should eq(false)
        end
      end

      context 'empty password field' do
        it 'returns false' do
          user = described_class::User.first
          user.password = ''
          user.save!

          subject.validate('test', 'wrongpassword').should eq(false)
        end
      end
    end

    context 'invalid username' do
      it 'returns false' do
        subject.validate('does-not-exist', 'testpassword').should eq(false)
      end
    end

    context 'support for bcrypt' do
      before do
        described_class::User.create!(
          username: 'test2',
          password: '$2a$10$dRFLSkYedQ05sqMs3b265e0nnJSoa9RhbpKXU79FDPVeuS1qBG7Jq', # password: testpassword2
          mail_address: 'mail@example.org')
      end

      it 'is able to handle bcrypt password hashes' do
        subject.validate('test2', 'testpassword2').should be_instance_of(Hash)
      end
    end

    context 'support for bcrypt with pepper' do
      let(:pepper) { 'abcdefg' }

      before do
        described_class::User.create!(
          username: 'test3',
          password: '$2a$10$ndCGPWg5JFMQH/Kl6xKe.OGNaiG7CFIAVsgAOJU75Q6g5/FpY5eX6', # password: testpassword3, pepper: abcdefg
          mail_address: 'mail@example.org')
      end

      it 'is able to handle bcrypt password hashes' do
        subject.validate('test3', 'testpassword3').should be_instance_of(Hash)
      end
    end

    context 'support for phpass' do
      before do
        described_class::User.create!(
          username: 'test4',
          password: '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0', # password: test12345
          mail_address: 'mail@example.org')
      end

      it 'is able to handle phpass password hashes' do
        subject.validate('test4', 'test12345').should be_instance_of(Hash)
      end
    end

    context 'support for pbkdf2 sha256' do
      before do
        described_class::User.create!(
                                      username: 'test5',
                                      password: '95022b869a6bf57779d7f5a66430b0fd6e11659400f540c3475af5ca63875f37', # password: test12345
                                      password_salt: 'ffc12e9ed7b3c74f3102b1f78e99c348',
                                      mail_address: 'mail@example.org')
      end

      it 'is able to handle pbkdf2:sha256 password hashes' do
        subject.validate('test5', "test12345").should be_instance_of(Hash)
      end
    end

    context 'support for bans' do
      before do
        described_class::User.create!(
                                      username: 'test6',
                                      password: '95022b869a6bf57779d7f5a66430b0fd6e11659400f540c3475af5ca63875f37', # password: test12345
                                      password_salt: 'ffc12e9ed7b3c74f3102b1f78e99c348',
                                      mail_address: 'mail@example.org',
                                      suspended_til: '2014-07-09 07:05:09.210632')
      end

      it 'is able to handle pbkdf2:sha256 banning' do
        subject.validate('test6', "test12345").should eq(false)
      end
    end
  end

end
