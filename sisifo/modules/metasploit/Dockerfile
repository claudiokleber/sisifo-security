FROM metasploitframework/metasploit-framework:latest
USER root
# Remove file capabilities inherited by Ruby; this adapter only uses normal TCP.
RUN setcap -r "$(readlink -f "$(command -v ruby)")"
COPY runner.rb /opt/sisifo/runner.rb
ENV HOME=/tmp
USER 65534:65534
ENTRYPOINT ["ruby", "/opt/sisifo/runner.rb"]
