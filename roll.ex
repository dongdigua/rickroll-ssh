defmodule RickRoll do
  require Logger
  @frame_time 40
  @frame_height 32
  @rick "./astley80.full"
  @port 2233

  def start() do
    Logger.configure(level: :info)
    :ok = :ssh.start()
    IO.inspect :erlang.memory
    accept()
  end

  def accept() do
    # inet6 is fine since OS uses dual-stack
    {:ok, socket} =
      :gen_tcp.listen(@port, [:inet6, packet: 0, active: false, reuseaddr: true])
    {:ok, _} =
      Agent.start_link(fn -> %{} end, name: :pubkey_store)
    {:ok, _} =
      RickRoll.KbInt.start()
    Logger.info("Listening on #{@port}")
    loop_acceptor(socket)
  end

  defp loop_acceptor(socket) do
    {:ok, client} = :gen_tcp.accept(socket)
    # 为了识别用户，得套一层 gen_tcp
    pid = spawn(fn ->
      Logger.info("Got victim #{inspect(client)}")
      :ssh.daemon(client, [
            system_dir: ~c"./ssh",
            id_string: ~c"SSH-2.0-OpenSSH_RickRoll",
            max_sessions: 1,
            shell: &roll(&1, client),
            # keyboard-interactive for optional PoW
            auth_methods: ~c"publickey,keyboard-interactive",
            auth_method_kb_interactive_data: RickRoll.KbInt.kb_int_fun(client),
            pwdfun: RickRoll.KbInt.pwdfun(client),
            # log every key
            key_cb: {RickRoll.KeyCb, [client: client]},
          ])
    end)
    :gen_tcp.controlling_process(client, pid) # socket ownership
    loop_acceptor(socket)
  end

  defmodule KeyCb do
    @behaviour :ssh_server_key_api

    def host_key(algorithm, options) do
      # fallback
      :ssh_file.host_key(algorithm, options)
    end

    def is_auth_key(pk, user, options) do
      client = options[:key_cb_private][:client]
      encoded = :ssh_file.encode([{pk, [comment: user]}], :openssh_key) |> String.trim
      Logger.info(encoded)
      Agent.update(:pubkey_store, fn state ->
        Map.update(state, client, [encoded], fn l -> [encoded|l] end)
      end)
      false
    end
  end

  defmodule KbInt do
    @difficulty 4 # 0 to disable PoW
    @prefix String.duplicate("0", @difficulty)

    def start(), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

    def kb_int_fun(client) when @difficulty > 0 do
      nonce = :crypto.strong_rand_bytes(16) |> :binary.encode_hex()
      Agent.update(__MODULE__, fn state -> Map.put(state, client, nonce) end)
      fn _,_,_ ->
        {"Making sure you are a robot", "SM3('#{nonce}'+?) == #{@prefix}...", "? = ", true}
      end
    end

    def kb_int_fun(_client) do
      fn _,_,_ -> {"", "", "password: ", false} end
    end

    def pwdfun(client) when @difficulty > 0 do
      nonce = Agent.get(__MODULE__, fn state -> state[client] end)
      fn _,pass,_,_ ->
        Agent.update(__MODULE__, fn state -> Map.delete(state, client) end)
        Logger.info("PoW: #{pass}")
        if String.starts_with?(:crypto.hash(:sm3, nonce <> List.to_string(pass)) |> :binary.encode_hex(), @prefix) do
          true
        else
          :disconnect
        end
      end
    end

    def pwdfun(_client) do
      fn user, pass ->
        Logger.info("user: #{user} password: #{pass}")
        true
      end
    end
  end

  def roll(_user, client) do
    spawn(fn ->
      parent = self()
      spawn(fn ->
        case IO.gets("") do
          {:error, reason} when reason in [:interrupted, :terminated] ->
            IO.puts IO.ANSI.reset
            IO.puts "Your pubkeys:"
            Agent.get(:pubkey_store, fn x -> Map.get(x, client) end) |> Enum.each(&IO.puts(&1))
            IO.puts "#{IO.ANSI.red}Identity noted. Expect a visit soon!#{IO.ANSI.reset}"
            Process.exit(parent, "")
        end
      end)

      File.stream!(@rick, read_ahead: 16384 * 4)
      |> Stream.chunk_every(@frame_height)
      |> Stream.each(fn frame ->
        frame
        |> Enum.join # roughly 16384 in size
        |> IO.write
        Process.sleep(@frame_time)
      end)
      |> Stream.run()
    end)
  end
end

RickRoll.start()
