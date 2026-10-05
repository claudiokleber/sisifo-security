FROM metasploitframework/metasploit-framework@sha256:a05bb5cac4c4d95b2ebeb972813ce17b2da022d7647c4f17e9537bffa2906ed6
USER root
# Remove file capabilities inherited by Ruby; this adapter only uses normal TCP.
RUN setcap -r "$(readlink -f "$(command -v ruby)")"
COPY runner.rb /opt/sisifo/runner.rb
ENV HOME=/tmp
USER 65534:65534
ENTRYPOINT ["ruby", "/opt/sisifo/runner.rb"]
