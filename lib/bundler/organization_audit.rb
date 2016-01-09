require "bundler/organization_audit/version"
require "bundler/audit/cli"
require "bundler/audit/database"
require "organization_audit"

module Bundler
  module OrganizationAudit
    class << self
      def run(options)
        @database = Bundler::Audit::Database.new
        @ignore = options[:ignore_advisories] || []
        vulnerable = find_vulnerable(options)
        if vulnerable.size == 0
          0
        else
          $stderr.puts "Vulnerable:"
          puts vulnerable
          1
        end
      end

      private

      def find_vulnerable(options)
        ::OrganizationAudit.all(options).select do |repo|
          begin
            next if options[:ignore_gems] && repo.gem?
          rescue OpenURI::HTTPError => e
            if e.message.include?('This repository is empty')
              puts "Failed to audit empty repo #{repo.name} -- #{e}"
            else
              raise
            end
          end
          audit_repo(repo, options)
        end
      end

      def audit_repo(repo, options)
        vulnerable = false
        $stderr.puts repo.name
        if gemfile_dot_lock = repo.content("Gemfile.lock")
          if vulnerable?(gemfile_dot_lock)
            vulnerable = true
          end
        else
          $stderr.puts "No Gemfile.lock found"
        end
        $stderr.puts ""
        vulnerable
      rescue Exception => e
        $stderr.puts "Error auditing #{repo.name} (#{e})"
        true
      end

      def vulnerable?(file)
        vulnerable = false
        Bundler::LockfileParser.new(file).specs.each do |gem|
          @database.check_gem(gem) do |advisory|
            next if @ignore.include?(advisory.id)
            next unless advisory.vulnerable?(gem.version)

            print_advisory(gem, advisory)
            vulnerable = true
          end
        end
        vulnerable
      end

      def print_advisory(gem, advisory)
        @interface ||= Bundler::Audit::CLI.new
        @interface.send(:print_advisory, gem, advisory)
      end
    end
  end
end
