#include <iostream>
#include <iomanip>       
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <openssl/evp.h> 
#include <openssl/sha.h>
#include <vector>
#include <map>
#include <cstdlib>
#include <ctime>
#include <thread>

#define CHUNK_SIZE (512 * 1024)
using namespace std;

struct ChunkInfo 
{
    size_t chunk_number;
    string hash;
};

string calculateSHA1(const char* data, size_t size) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) 
    {
        cerr << "Failed to create EVP_MD_CTX" << endl;
        return "";
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)) {
        cerr << "EVP_DigestInit_ex failed" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    if (1 != EVP_DigestUpdate(mdctx, data, size)) 
    {
        cerr << "EVP_DigestUpdate failed" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) 
    {
        cerr << "EVP_DigestFinal_ex failed" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

string calculateFileSHA1(const string& file_path) 
{
    int file_fd = open(file_path.c_str(), O_RDONLY);
    if (file_fd < 0) 
    {
        return "";
    }

    char buffer[CHUNK_SIZE];
    ssize_t bytes_read;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) 
    {
        close(file_fd);
        return "";
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)) 
    {
        EVP_MD_CTX_free(mdctx);
        close(file_fd);
        return "";
    }

    while ((bytes_read = read(file_fd, buffer, CHUNK_SIZE)) > 0) 
    {
        if (1 != EVP_DigestUpdate(mdctx, buffer, bytes_read)) {
            EVP_MD_CTX_free(mdctx);
            close(file_fd);
            return "";
        }
    }

    close(file_fd);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];

    return ss.str();
}

struct UploadInfo {
    string file_path;
    off_t file_size;
    vector<ChunkInfo> chunks;
};

string tracker_ip;
int tracker_port;
int client_listen_port;

map<string, UploadInfo> uploaded_files;

void* peerServer(void* arg);

int main(int argc, char* argv[]) {
    if (argc != 3) 
    {
        cerr << "Usage: ./client <IP>:<PORT> tracker_info.txt" << endl;
        return 1;
    }

    string ip_port = argv[1];
    size_t colon_pos = ip_port.find(':');

    tracker_ip = ip_port.substr(0, colon_pos);
    tracker_port = stoi(ip_port.substr(colon_pos + 1));

    if (tracker_port < 1024 || tracker_port > 65535) 
    {
        cerr << "Invalid tracker port number. Port must be between 1024 and 65535." << endl;
        return 1;
    }

    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) 
    {
        cerr << "Failed to open tracker info file." << endl;
        return 1;
    }

    char buffer[256];
    ssize_t bytes_read;
    string data;

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) 
    {
        buffer[bytes_read] = '\0';
        data += buffer;
    }
    close(fd);

    istringstream iss(data);
    string ip;
    int port;
    bool tracker_found = false;
    int sock = -1;
    while (iss >> ip >> port) 
    {
        cout << "Tracker IP: " << ip << ", Port: " << port << endl;

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) 
        {
            perror("Socket creation error");
            return -1;
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) 
        {
            perror("Invalid address/Address not supported");
            close(sock);
            continue;
        }

        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
            cout << "Connected to tracker at " << ip << ":" << port << endl;
            tracker_ip = ip;
            tracker_port = port;
            tracker_found = true;
            break;
        } 
        else 
        {
            perror("Connection Failed");
            close(sock);
        }
    }

    if (!tracker_found) {
        cerr << "No tracker is currently online." <<endl;
        return 1;
    }

    srand(time(NULL));
    client_listen_port = 50000 + rand() % 10000; // Random port between 50000 and 59999

    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, peerServer, NULL) < 0) 
    {
        perror("Could not create peer server thread");
        return 1;
    }

    bool logged_in = false;
    bool group_operation_done = false;
    bool running = true;
    bool in_group = false;
    char buffer_client[4096];

    while (running) {
        if (!logged_in) {
            cout <<endl<< "create_user " <<endl;
            cout << "login" <<endl;
            cout << "exit" <<endl;
            cout << "Enter your choice: ";
            string choice;
            
            getline(cin, choice);

            if (choice == "create_user") {
                string username, password;
                cout << "Enter username: ";
                getline(cin, username);
                cout << "Enter password: ";
                getline(cin, password);
                string register_message = "register " + username + " " + password;
                if (write(sock, register_message.c_str(), register_message.size()) < 0) {
                    perror("Write to tracker failed");
                    continue;
                }

                // Receive acknowledgment from tracker
                int read_size = read(sock, buffer_client, sizeof(buffer_client));
                if (read_size > 0) 
                {
                    buffer_client[read_size] = '\0';
                    cout << "Tracker response: " << buffer_client << endl;
                } 
                else if (read_size < 0) 
                {
                    perror("Read from tracker failed");
                }
            } else if (choice == "login") {
                string username, password;
                cout << "Enter username: ";
                getline(cin, username);
                cout << "Enter password: ";
                getline(cin, password);
                string login_message = "login " + username + " " + password;
                if (write(sock, login_message.c_str(), login_message.size()) < 0) 
                {
                    perror("Write to tracker failed");
                    continue;
                }

                int read_size = read(sock, buffer_client, sizeof(buffer_client));
                if (read_size > 0) {
                    buffer_client[read_size] = '\0';
                    cout << "Tracker response: " << buffer_client << endl;
                    if (string(buffer_client) == "Login successful") {
                        logged_in = true;
                    }
                } else if (read_size < 0) {
                    perror("Read from tracker failed");
                }
            } else if (choice == "exit") {
                running = false;
            } else {
                cout << "Invalid choice. Please try again." << std::endl;
            }
        } 
        else {
            if (!group_operation_done) {
                cout << "\nLogged-in Menu:\n";
                cout << "create_group <group_name> - Create a group\n";
                cout << "join_group <group_name> - Join a group\n";
                cout << "logout - Logout\n";
                cout << "Enter your choice: ";
                string choice;
                getline(cin, choice);

                if (choice == "logout") {
                    logged_in = false;
                    in_group = false;
                    string logout_message = "logout";
                    if (write(sock, logout_message.c_str(), logout_message.size()) < 0) {
                        perror("Write to tracker failed");
                        continue;
                    }

                    int read_size = read(sock, buffer_client, sizeof(buffer_client));
                    if (read_size > 0) {
                        buffer_client[read_size] = '\0';
                        cout << "Tracker response: " << buffer_client << endl;
                    } else if (read_size < 0) {
                        perror("Read from tracker failed");
                    }
                } else if (choice.rfind("create_group", 0) == 0) 
                {
                    if (write(sock, choice.c_str(), choice.size()) < 0) 
                    {
                        perror("Write to tracker failed");
                        continue;
                    }

                    int read_size = read(sock, buffer_client, sizeof(buffer_client));
                    if (read_size > 0) 
                    {
                        buffer_client[read_size] = '\0';
                        cout << "Tracker response: " << buffer_client << endl;
                        group_operation_done = true;
                        in_group = true;
                    } 
                    else if (read_size < 0) 
                    {
                        perror("Read from tracker failed");
                    }
                } 
                else if (choice.rfind("join_group", 0) == 0) 
                {
                    if (write(sock, choice.c_str(), choice.size()) < 0) 
                    {
                        perror("Write to tracker failed");
                        continue;
                    }

                    int read_size = read(sock, buffer_client, sizeof(buffer_client));
                    if (read_size > 0) {
                        buffer_client[read_size] = '\0';
                        cout << "Tracker response: " << buffer_client << endl;
                        group_operation_done = true;
                        in_group = true;
                    } else if (read_size < 0) {
                        perror("Read from tracker failed");
                    }
                } else {
                    cout << "Invalid choice. Please try again." << endl;
                }
            } else {
                cout <<endl <<"Logged-in Menu:"<<endl;
                cout << "upload_file "<<endl;
                cout << "download_file" <<endl;
                cout << "logout - Logout" <<endl;
                cout <<"leave_group"<<endl;
                cout << "Enter your choice: " <<endl;
                string choice;
                getline(cin, choice);

                if (choice == "logout") 
                {
                    logged_in = false;
                    group_operation_done = false;
                    in_group = false;
                    string logout_message = "logout";
                    if (write(sock, logout_message.c_str(), logout_message.size()) < 0) 
                    {
                        perror("Write to tracker failed");
                        continue;
                    }

                    int read_size = read(sock, buffer_client, sizeof(buffer_client));
                    if (read_size > 0) {
                        buffer_client[read_size] = '\0';
                        cout << "Tracker response: " << buffer_client << endl;
                    } 
                    else if (read_size < 0) 
                    {
                        perror("Read from tracker failed");
                    }
                } 
                else if (choice == "upload_file") 
                {
                    if (!in_group) {
                        cout << "You need to be in a group to upload files." << endl;
                        continue;
                    }
                    cout << "Enter the file path to upload: ";
                    string file_path;
                    getline(cin, file_path);

                    // Open the file
                    int file_fd = open(file_path.c_str(), O_RDONLY);
                    if (file_fd < 0) {
                        perror("Failed to open file");
                        continue;
                    }

                    struct stat file_stat;
                    if (fstat(file_fd, &file_stat) < 0) 
                    {
                        perror("Failed to get file stats");
                        close(file_fd);
                        continue;
                    }
                    off_t file_size = file_stat.st_size;

                    string file_name = file_path.substr(file_path.find_last_of("/\\") + 1);

                    char buffer[CHUNK_SIZE];
                    ssize_t bytes_read;
                    size_t chunk_number = 0;
                    vector<ChunkInfo> chunks;
                    while ((bytes_read = read(file_fd, buffer, CHUNK_SIZE)) > 0) 
                    {
                        string chunk_hash = calculateSHA1(buffer, bytes_read);
                        chunks.push_back({chunk_number, chunk_hash});
                        chunk_number++;
                    }

                    close(file_fd);

                    string file_hash = calculateFileSHA1(file_path);

                    ostringstream oss;
                    oss << "upload_file_metadata " << file_name << " " << file_size << " " << client_listen_port << " " << file_hash << " " << chunks.size();
                    for (const auto& chunk : chunks) 
                    {
                        oss << " " << chunk.hash;
                    }

                    string upload_message = oss.str();

                    if (write(sock, upload_message.c_str(), upload_message.size()) < 0) 
                    {
                        perror("Write to tracker failed");
                        continue;
                    }

                    int read_size = read(sock, buffer_client, sizeof(buffer_client));
                    if (read_size > 0) {
                        buffer_client[read_size] = '\0';
                        cout << "Tracker response: " << buffer_client << endl;
                        if (string(buffer_client) == "File metadata received") 
                        {


                            uploaded_files[file_name] = {file_path, file_size, chunks};
                            cout << "File upload metadata sent to tracker successfully." << endl;
                        }
                    } 
                    else if (read_size < 0) 
                    {
                        perror("Read from tracker failed");
                    }
                } else if (choice == "download_file") {
                    cout << "Enter the file name to download: ";
                    string file_name;
                    getline(cin, file_name);

                    string download_message = "download_file " + file_name;
                    if (write(sock, download_message.c_str(), download_message.size()) < 0) 
                    {
                        perror("Write to tracker failed");
                        continue;
                    }

                    int read_size = read(sock, buffer_client, sizeof(buffer_client));
                    if (read_size <= 0) 
                    {
                        perror("Failed to receive file metadata from tracker");
                        continue;
                    }
                    buffer_client[read_size] = '\0';

                    string response(buffer_client);
                    if (response == "File not found") {
                        cout << "Tracker response: " << response << endl;
                        continue;
                    }

                    // format: <file_size> <file_hash> <num_chunks> <chunk_hashes> <num_seeders> <seeder_ip> <seeder_port> ...
                    istringstream iss(response);
                    off_t file_size;
                    string file_hash;
                    size_t num_chunks;

                    iss >> file_size >> file_hash >> num_chunks;

                    vector<string> chunk_hashes(num_chunks);
                    for (size_t i = 0; i < num_chunks; ++i) 
                    {
                        iss >> chunk_hashes[i];
                    }

                    size_t num_seeders;
                    iss >> num_seeders;
                    vector<pair<string, int>> seeders;
                    for (size_t i = 0; i < num_seeders; ++i) 
                    {
                        string seeder_ip;
                        int seeder_port;
                        iss >> seeder_ip >> seeder_port;
                        seeders.emplace_back(seeder_ip, seeder_port);
                    }

                    string save_file_path = "downloads/" + file_name;
                    mkdir("downloads", 0777);
                    int save_fd = open(save_file_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
                    if (save_fd < 0) 
                    {
                        perror("Failed to open file for writing");
                        continue;
                    }

                    for (size_t chunk_num = 0; chunk_num < num_chunks; ++chunk_num) 
                    {
                        int peer_sock = socket(AF_INET, SOCK_STREAM, 0);
                        if (peer_sock < 0) {
                            perror("Socket creation error");
                            close(save_fd);
                            continue;
                        }

                        struct sockaddr_in peer_addr;
                        peer_addr.sin_family = AF_INET;
                        peer_addr.sin_port = htons(seeders[0].second);
                        if (inet_pton(AF_INET, seeders[0].first.c_str(), &peer_addr.sin_addr) <= 0) 
                        {
                            perror("Invalid address/Address not supported");
                            close(peer_sock);
                            close(save_fd);
                            continue;
                        }

                        if (connect(peer_sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) 
                        {
                            perror("Connection to peer failed");
                            close(peer_sock);
                            close(save_fd);
                            continue;
                        }

                        string chunk_request = "get_chunk " + file_name + " " + to_string(chunk_num);
                        if (write(peer_sock, chunk_request.c_str(), chunk_request.size()) < 0) {
                            perror("Failed to send chunk request");
                            close(peer_sock);
                            close(save_fd);
                            continue;
                        }

                        char chunk_size_buf[32];
                        int size_read = read(peer_sock, chunk_size_buf, sizeof(chunk_size_buf));
                        if (size_read <= 0) {
                            perror("Failed to read chunk size");
                            close(peer_sock);
                            continue;
                        }
                        string chunk_size_str(chunk_size_buf, size_read);

                        if (chunk_size_str.find("ERROR") == 0) {
                            cerr << "Seeder response: " << chunk_size_str << endl;
                            close(peer_sock);
                            continue;
                        }

                        size_t chunk_size = stoul(chunk_size_str);

                        const char* ack = "ACK";
                        write(peer_sock, ack, strlen(ack));

                        char* chunk_data = new char[chunk_size];
                        size_t bytes_received = 0;
                        while (bytes_received < chunk_size) 
                        {
                            ssize_t len = read(peer_sock, chunk_data + bytes_received, chunk_size - bytes_received);
                            if (len <= 0) {
                                perror("Failed to read chunk data");
                                break;
                            }
                            bytes_received += len;
                        }

                        close(peer_sock);

                        string received_chunk_hash = calculateSHA1(chunk_data, chunk_size);
                        if (received_chunk_hash != chunk_hashes[chunk_num]) 
                        {
                            cerr << "Chunk verification failed for chunk " << chunk_num << endl;
                            delete[] chunk_data;
                            continue;
                        }

                        if (write(save_fd, chunk_data, chunk_size) < 0) 
                        {
                            perror("Failed to write to file");
                            delete[] chunk_data;
                            continue;
                        }

                        delete[] chunk_data;

                        cout << "Downloaded and integrated the Metadata " << chunk_num << endl;
                    }

                    close(save_fd);

                    string downloaded_file_hash = calculateFileSHA1(save_file_path);
                    if (downloaded_file_hash != file_hash) 
                    {
                        cerr << "File verification failed after download." << endl;
                    } 
                    else {
                        cout << "File downloaded successfully in your downloads directory." << endl;
                    }

                } 
                else 
                {
                    cout << "Invalid choice. Please try again." << endl;
                }
            }
        }
    }

    close(sock);
    return 0;
}

void* peerServer(void* arg) 
{
    int server_sock, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Peer server socket failed");
        pthread_exit(NULL);
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Set socket options failed");
        close(server_sock);
        pthread_exit(NULL);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(client_listen_port);

    if (bind(server_sock, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Peer server bind failed");
        close(server_sock);
        pthread_exit(NULL);
    }

    cout << "Peer server listening on port " << client_listen_port << endl;

    if (listen(server_sock, 10) < 0) 
    {
        perror("Peer server listen failed");
        close(server_sock);
        pthread_exit(NULL);
    }

    while ((new_socket = accept(server_sock, (struct sockaddr*)&address, (socklen_t*)&addrlen)) >= 0) {

        pthread_t handler_thread;
        int* new_sock = new int;
        *new_sock = new_socket;

        auto peerHandler = [](void* socket_desc) -> void* {
            int sock = *(int*)socket_desc;
            delete (int*)socket_desc;

            char buffer[1024];
            int read_size = read(sock, buffer, sizeof(buffer));
            if (read_size <= 0) {
                close(sock);
                pthread_exit(NULL);
            }
            string request(buffer, read_size);

            // Expected format: get_chunk <file_name> <chunk_number>
            istringstream iss(request);
            string command, file_name;
            size_t chunk_number;
            iss >> command >> file_name >> chunk_number;

            if (command != "get_chunk") {
                close(sock);
                pthread_exit(NULL);
            }

            if (uploaded_files.find(file_name) == uploaded_files.end()) 
            {
                string error_msg = "ERROR: File not available";
                write(sock, error_msg.c_str(), error_msg.size());
                close(sock);
                pthread_exit(NULL);
            }

            string file_path = uploaded_files[file_name].file_path;
            int file_fd = open(file_path.c_str(), O_RDONLY);
            if (file_fd < 0) 
            {
                perror("Failed to open file for reading");
                string error_msg = "ERROR: File not available";
                write(sock, error_msg.c_str(), error_msg.size());
                close(sock);
                pthread_exit(NULL);
            }

            off_t offset = chunk_number * CHUNK_SIZE;
            if (lseek(file_fd, offset, SEEK_SET) < 0) 
            {
                perror("Failed to seek to chunk position");
                close(file_fd);
                close(sock);
                pthread_exit(NULL);
            }

            char* chunk_data = new char[CHUNK_SIZE];
            ssize_t bytes_read = read(file_fd, chunk_data, CHUNK_SIZE);
            if (bytes_read <= 0) 
            {
                perror("Failed to read chunk data");
                delete[] chunk_data;
                close(file_fd);
                close(sock);
                pthread_exit(NULL);
            }

            close(file_fd);

            string chunk_size_str = to_string(bytes_read);
            if (write(sock, chunk_size_str.c_str(), chunk_size_str.size()) < 0) 
            {

                perror("Failed to send chunk size");
                delete[] chunk_data;
                close(sock);
                pthread_exit(NULL);
            }

            read_size = read(sock, buffer, sizeof(buffer));
            if (read_size <= 0) {
                perror("Failed to receive acknowledgment");
                delete[] chunk_data;
                close(sock);
                pthread_exit(NULL);
            }

            if (write(sock, chunk_data, bytes_read) < 0) {
                perror("Failed to send chunk data");
                delete[] chunk_data;
                close(sock);
                pthread_exit(NULL);
            }

            delete[] chunk_data;
            close(sock);
            pthread_exit(NULL);
        };

        if (pthread_create(&handler_thread, NULL, peerHandler, (void*)new_sock) < 0) {
            perror("Could not create peer handler thread");
            delete new_sock;
        } else {
            pthread_detach(handler_thread);
        }
    }

    close(server_sock);
    pthread_exit(NULL);
}
