Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-20.04"

  config.vm.provision "ansible" do |ansible|
    ansible.playbook = "playbook.yml"
  end

end
