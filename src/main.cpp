#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QTreeView>
#include <QStandardItemModel>
#include <QFileDialog>
#include <QDesktopServices>
#include <QUrl>
#include <pcap.h>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <vector>
#include <fstream>
#include <iostream>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// comment here

const char *DESTINATION_IP = "255.255.255.255";
const uint16_t SOURCE_PORT = 14236;
const uint16_t DESTINATION_PORT = 14235;

struct PacketInfo
{
    std::string source_ip;
    std::string source_mac;

    bool operator==(const PacketInfo &other) const
    {
        return source_ip == other.source_ip && source_mac == other.source_mac;
    }
};

namespace std
{
    template <>
    struct hash<PacketInfo>
    {
        size_t operator()(const PacketInfo &pi) const
        {
            return hash<string>()(pi.source_ip) ^ hash<string>()(pi.source_mac);
        }
    };
}

class IPReporter : public QMainWindow
{
    Q_OBJECT

public:
    IPReporter(QWidget *parent = nullptr);
    ~IPReporter();

private slots:
    void on_start_button_clicked();
    void on_export_button_clicked();
    void on_tree_view_double_clicked(const QModelIndex &index);

private:
    void capture_packets();
    void update_tree_view(const PacketInfo &info);
    PacketInfo extract_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

    QWidget *centralWidget;
    QVBoxLayout *vboxLayout;
    QTreeView *treeView;
    QStandardItemModel *model;
    QPushButton *startButton;
    QPushButton *exportButton;
    QLabel *statusLabel;

    std::thread captureThread;
    std::mutex mtx;
    bool listening;
    std::vector<PacketInfo> packets;
    std::unordered_set<PacketInfo> unique_packets;
};

IPReporter::IPReporter(QWidget *parent)
    : QMainWindow(parent), listening(false)
{
    centralWidget = new QWidget(this);
    vboxLayout = new QVBoxLayout(centralWidget);

    model = new QStandardItemModel(0, 2, this);
    model->setHeaderData(0, Qt::Horizontal, "IP Address");
    model->setHeaderData(1, Qt::Horizontal, "MAC Address");

    treeView = new QTreeView(this);
    treeView->setModel(model);
    connect(treeView, &QTreeView::doubleClicked, this, &IPReporter::on_tree_view_double_clicked);

    startButton = new QPushButton("Start", this);
    exportButton = new QPushButton("Export", this);
    statusLabel = new QLabel("Stopped", this);

    vboxLayout->addWidget(treeView);
    vboxLayout->addWidget(startButton);
    vboxLayout->addWidget(exportButton);
    vboxLayout->addWidget(statusLabel);

    setCentralWidget(centralWidget);

    connect(startButton, &QPushButton::clicked, this, &IPReporter::on_start_button_clicked);
    connect(exportButton, &QPushButton::clicked, this, &IPReporter::on_export_button_clicked);
}

IPReporter::~IPReporter()
{
    listening = false;
    if (captureThread.joinable())
    {
        captureThread.join();
    }
}

void IPReporter::on_start_button_clicked()
{
    std::lock_guard<std::mutex> lock(mtx);
    if (!listening)
    {
        listening = true;
        startButton->setText("Stop");
        statusLabel->setText("Listening...");
        captureThread = std::thread(&IPReporter::capture_packets, this);
    }
    else
    {
        listening = false;
        startButton->setText("Start");
        statusLabel->setText("Stopped");
    }
}

void IPReporter::on_export_button_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Save File", "", "Text Files (*.txt);;All Files (*)");
    if (!fileName.isEmpty())
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::ofstream file(fileName.toStdString());
        for (const auto &info : packets)
        {
            file << "IP Address: " << info.source_ip << ", MAC Address: " << info.source_mac << "\n";
        }
        statusLabel->setText("Data exported.");
    }
}

void IPReporter::on_tree_view_double_clicked(const QModelIndex &index)
{
    QString ipAddress = model->data(model->index(index.row(), 0)).toString();
    QString url = QString("http://root:root@%1").arg(ipAddress);
    QDesktopServices::openUrl(QUrl(url));
}

void IPReporter::capture_packets()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }

    // Print available devices
    for (device = alldevs; device != nullptr; device = device->next)
    {
        std::cout << "Device: " << device->name << " - " << (device->description ? device->description : "No description") << std::endl;
    }

    device = alldevs; // Use the first device, update this to use the correct device if needed
    std::cout << "Using device: " << device->name << std::endl;

    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return;
    }

    while (listening)
    {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if (packet != nullptr)
        {
            std::cout << "Packet captured: length = " << header.len << std::endl;
            PacketInfo info = extract_packet_info(packet, header);
            if (!info.source_ip.empty() && !info.source_mac.empty())
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (unique_packets.insert(info).second)
                {
                    packets.push_back(info);
                    update_tree_view(info);
                }
            }
        }
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
}

// non-freebsd code

// PacketInfo IPReporter::extract_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
// {
//     PacketInfo info;

//     struct ether_header *eth_header;
//     eth_header = (struct ether_header *)packet;

//     // Check if it's an IP packet
//     if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
//     {
//         std::cerr << "Not an IP packet" << std::endl;
//         return info;
//     }

//     // Extract source MAC address
//     char mac_addr[18];
//     snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
//              eth_header->ether_shost[0],
//              eth_header->ether_shost[1],
//              eth_header->ether_shost[2],
//              eth_header->ether_shost[3],
//              eth_header->ether_shost[4],
//              eth_header->ether_shost[5]);
//     info.source_mac = mac_addr;

//     struct ip *ip_header;
//     ip_header = (struct ip *)(packet + sizeof(struct ether_header));

//     // Check if the packet's destination IP matches the specified destination IP
//     char ip_addr[INET_ADDRSTRLEN];
//     inet_ntop(AF_INET, &(ip_header->ip_dst), ip_addr, INET_ADDRSTRLEN);
//     if (strcmp(ip_addr, DESTINATION_IP) != 0)
//     {
//         std::cerr << "Destination IP does not match" << std::endl;
//         return info;
//     }

//     // Check if the packet is a UDP packet
//     if (ip_header->ip_p != IPPROTO_UDP)
//     {
//         std::cerr << "Not a UDP packet" << std::endl;
//         return info;
//     }

//     // Extract the UDP header
//     struct udphdr *udp_header;
//     udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

//     // Check if the source and destination ports match
//     if (ntohs(udp_header->source) != SOURCE_PORT || ntohs(udp_header->dest) != DESTINATION_PORT)
//     {
//         std::cerr << "Ports do not match" << std::endl;
//         return info;
//     }

//     // Extract source IP address
//     inet_ntop(AF_INET, &(ip_header->ip_src), ip_addr, INET_ADDRSTRLEN);
//     info.source_ip = ip_addr;

//     // Debug output
//     std::cout << "Source IP: " << info.source_ip << std::endl;
//     std::cout << "Source MAC: " << info.source_mac << std::endl;

//     return info;
// }

// freebsd code

PacketInfo IPReporter::extract_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
    PacketInfo info;

    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        std::cerr << "Not an IP packet" << std::endl;
        return info;
    }

    // Extract source MAC address
    char mac_addr[18];
    snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_shost[0],
             eth_header->ether_shost[1],
             eth_header->ether_shost[2],
             eth_header->ether_shost[3],
             eth_header->ether_shost[4],
             eth_header->ether_shost[5]);
    info.source_mac = mac_addr;

    struct ip *ip_header;
    ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    // Check if the packet's destination IP matches the specified destination IP
    char ip_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_dst), ip_addr, INET_ADDRSTRLEN);
    if (strcmp(ip_addr, DESTINATION_IP) != 0)
    {
        std::cerr << "Destination IP does not match" << std::endl;
        return info;
    }

    // Check if the packet is a UDP packet
    if (ip_header->ip_p != IPPROTO_UDP)
    {
        std::cerr << "Not a UDP packet" << std::endl;
        return info;
    }

    // Extract the UDP header
    struct udphdr *udp_header;
    udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    // Check if the source and destination ports match
    if (ntohs(udp_header->uh_sport) != SOURCE_PORT || ntohs(udp_header->uh_dport) != DESTINATION_PORT)
    {
        std::cerr << "Ports do not match" << std::endl;
        return info;
    }

    // Extract source IP address
    inet_ntop(AF_INET, &(ip_header->ip_src), ip_addr, INET_ADDRSTRLEN);
    info.source_ip = ip_addr;

    // Debug output
    std::cout << "Source IP: " << info.source_ip << std::endl;
    std::cout << "Source MAC: " << info.source_mac << std::endl;

    return info;
}

void IPReporter::update_tree_view(const PacketInfo &info)
{
    QStandardItem *ipItem = new QStandardItem(QString::fromStdString(info.source_ip));
    QStandardItem *macItem = new QStandardItem(QString::fromStdString(info.source_mac));
    QList<QStandardItem *> items = {ipItem, macItem};
    model->appendRow(items);
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    IPReporter reporter;
    reporter.setWindowTitle("IP Reporter");
    reporter.resize(600, 400);
    reporter.show();

    return app.exec();
}

#include "main.moc"
